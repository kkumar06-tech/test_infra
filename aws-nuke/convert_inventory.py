"""Convert aws-nuke dry-run logs into inventory and optional baseline exclusions."""

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

import yaml


class InventoryDumper(yaml.SafeDumper):
    """Indent sequence entries beneath their parent key."""

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, indentless=False)


def dump_yaml(document):
    text = yaml.dump(
        document, Dumper=InventoryDumper, sort_keys=False,
        allow_unicode=False, indent=2,
    )
    lines = []
    spaced_sections = {"resources", "scan_errors"}
    section = None
    seen_item = False
    for line in text.splitlines(keepends=True):
        if line and not line[0].isspace():
            section = line.removesuffix(":\n")
            if section not in spaced_sections:
                section = None
            seen_item = False
        if section and line.startswith("  - "):
            if seen_item:
                lines.append("\n")
            seen_item = True
        lines.append(line)
    return "".join(lines)


class InventoryError(ValueError):
    """The log cannot be converted into a validated dry-run inventory."""


VOLATILE_PROPERTIES = {"createdtime", "status", "updatedat"}

# Known failures from the current scan. Match the cause, not just the type;
# request IDs and timestamps change between runs.
EXPECTED_LISTING_ERRORS = (
    ("CloudDirectorySchema", "is not authorized for region: eu-central-1"),
    ("CloudDirectoryDirectory", "is not authorized for region: eu-central-1"),
    ("CloudSearchDomain", "New domain creation not supported on this account"),
    ("Cloud9Environment", "This account does not have access to the Cloud9 service"),
    ("GlueDevEndpoint", "GetDevEndpoints operation is currently disabled"),
    ("FMSPolicy", "No default admin could be found for account"),
    ("FMSNotificationChannel", "No default admin could be found for account"),
    ("ShieldProtection", "ResourceNotFoundException: The subscription does not exist"),
    ("ShieldProtectionGroup", "ResourceNotFoundException: The subscription does not exist"),
    ("AWS::Timestream::Database", "Only existing Timestream for LiveAnalytics customers can access the service"),
    ("AWS::Timestream::Table", "Only existing Timestream for LiveAnalytics customers can access the service"),
    ("AWS::Timestream::ScheduledQuery", "Only existing Timestream for LiveAnalytics customers can access the service"),
    ("BedrockModelCustomizationJob", "UnknownOperationException: Unknown Operation"),
    ("LexBot", "status code: 503"),
    ("LexIntent", "status code: 503"),
    ("LexSlotType", "status code: 503"),
    ("LexModelBuildingServiceBotAlias", "status code: 503"),
    ("QBusinessApplication", "no such host"),
    ("QBusinessDataSource", "no such host"),
    ("QBusinessIndex", "no such host"),
    ("QBusinessPlugin", "no such host"),
    ("QBusinessRetriever", "no such host"),
    ("QBusinessWebExperience", "no such host"),
    ("OpsWorksApp", "no such host"),
    ("OpsWorksInstance", "no such host"),
    ("OpsWorksLayer", "no such host"),
    ("OpsWorksUserProfile", "no such host"),
    ("CodeStarProject", "i/o timeout"),
    ("OpsWorksCMBackup", "i/o timeout"),
    ("OpsWorksCMServer", "i/o timeout"),
    ("OpsWorksCMServerState", "i/o timeout"),
    ("InspectorAssessmentRun", "i/o timeout"),
    ("InspectorAssessmentTarget", "i/o timeout"),
    ("InspectorAssessmentTemplate", "i/o timeout"),
)


def convert_inventory(lines, account_id, regions, account_name):
    if not re.fullmatch(r"[0-9]{12}", account_id):
        raise InventoryError("Account ID must contain exactly 12 digits.")
    if not isinstance(account_name, str) or not account_name.strip():
        raise InventoryError("Provide a non-empty account name.")
    if not regions or any(not region.strip() for region in regions):
        raise InventoryError("Provide the regions used by the scan.")

    resources = {}
    scan_errors = []
    summary = None
    version = None
    started = False
    finished = False
    scan_time = None

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise InventoryError(f"Line {line_number}: invalid JSON: {error.msg}") from error
        if not isinstance(record, dict):
            raise InventoryError(f"Line {line_number}: expected a JSON object.")

        message = record.get("msg", "")
        if not isinstance(message, str):
            raise InventoryError(f"Line {line_number}: msg must be a string.")
        if record.get("level") in {"error", "fatal", "panic"} or "error" in record:
            if (
                record.get("level") == "error"
                and message.startswith("listing failed:")
                and isinstance(record.get("resource_type"), str)
                and record["resource_type"]
            ):
                scan_errors.append(record)
                continue
            raise InventoryError(f"Line {line_number}: scan reported an error: {message}")

        if message.startswith("aws-nuke - "):
            if version is not None:
                raise InventoryError("Multiple scans in one input are not supported.")
            version = message.split(" - ")[1]
        if message == "starting scan for resources":
            if started:
                raise InventoryError("Multiple scans in one input are not supported.")
            started = True
        if message.startswith("Scan complete:"):
            if summary is not None:
                raise InventoryError("Multiple scan summaries found.")
            raw_counts = {key: record.get(key) for key in ("total", "nukeable", "filtered")}
            if any(type(value) is not int or value < 0 for value in raw_counts.values()):
                raise InventoryError("Scan summary must contain non-negative integer counts.")
            summary = {
                "total": raw_counts["total"],
                "candidate": raw_counts["nukeable"],
                "filtered": raw_counts["filtered"],
            }
            scan_time = record.get("time")
        if message.startswith("The above resources would be deleted") or message == "No resource to delete.":
            finished = True

        if "type" not in record or "name" not in record:
            continue
        if not started or summary is not None:
            raise InventoryError(f"Line {line_number}: resource outside scan boundaries.")
        for field in ("type", "name", "owner"):
            if not isinstance(record.get(field), str) or not record[field]:
                raise InventoryError(f"Line {line_number}: missing resource field {field}.")
        if "all" not in regions and record["owner"] not in regions:
            raise InventoryError(f"Line {line_number}: resource region is outside declared scope.")

        if record.get("state") == "new" and message == "would remove":
            status = "candidate"
        elif record.get("state") == "filtered" and message.startswith("filtered:"):
            status = "filtered"
        else:
            raise InventoryError(f"Line {line_number}: unexpected resource state or decision.")

        properties = {
            key: value
            for key, value in sorted(record.items())
            if key.startswith("prop:")
            and key.removeprefix("prop:").casefold() not in VOLATILE_PROPERTIES
        }
        # Some resource types expose the same display name for distinct resources.
        resource_key = (
            record["owner"], record["type"], record["name"],
            json.dumps(
                {key.removeprefix("prop:"): value for key, value in properties.items()},
                sort_keys=True,
            ),
        )
        if resource_key in resources:
            raise InventoryError(f"Line {line_number}: duplicate resource identifier: {resource_key}")
        resource = {
            "type": record["type"],
            "name": record["name"],
            "owner": record["owner"],
            "status": status,
            "reason": message.removeprefix("filtered:").strip(),
            **properties,
        }
        resources[resource_key] = resource

    if not version or not started or summary is None or not finished or not scan_time:
        raise InventoryError("Missing version, scan boundaries, summary, or dry-run completion.")
    actual = {
        "total": len(resources),
        "candidate": sum(r["status"] == "candidate" for r in resources.values()),
        "filtered": sum(r["status"] == "filtered" for r in resources.values()),
    }
    if actual != summary:
        raise InventoryError(f"Resource counts {actual} do not match scan summary {summary}.")

    classified_errors = []
    for error in scan_errors:
        error_text = str(error.get("error", error.get("msg", "")))
        expected = any(
            error["resource_type"] == expected_type and fragment.casefold() in error_text.casefold()
            for expected_type, fragment in EXPECTED_LISTING_ERRORS
        )
        classified_errors.append({
            **error,
            "classification": "expected" if expected else "unexpected",
        })
    unexpected_error_count = sum(
        error["classification"] == "unexpected" for error in classified_errors
    )
    return {
        "schema_version": 1,
        "complete": unexpected_error_count == 0,
        "listing_complete": not scan_errors,
        "expected_listing_error_count": len(classified_errors) - unexpected_error_count,
        "unexpected_listing_error_count": unexpected_error_count,
        "scan_errors": [
            error for error in classified_errors if error["classification"] == "unexpected"
        ],
        "account_id": account_id,
        "account_name": account_name.strip(),
        "aws_nuke_version": version,
        "scan_time": scan_time,
        "scope": {"regions": sorted(set(regions))},
        "summary": summary,
        "resources": [resources[key] for key in sorted(resources)],
    }


# Verified against resources/*.go in aws-nuke v3.68.3. A None value uses String()
# (the logged name), not a property guessed from its spelling.
EXACT_PROPERTIES = {
    "AppConfigDeploymentStrategy": "ID",
    "AthenaDataCatalog": "Name",
    "AthenaWorkGroup": "ARN",
    "BedrockInferenceProfile": "ARN",
    "BudgetsBudget": "Name",
    "CloudFrontResponseHeadersPolicy": "ID",
    "CodeDeployDeploymentConfig": "Name",
    "DAXParameterGroup": "Name",
    "EC2DHCPOption": None,
    "EC2DefaultSecurityGroupRule": None,
    "EC2InternetGateway": None,
    "EC2InternetGatewayAttachment": None,
    "EC2NetworkACL": "ID",
    "EC2RouteTable": None,
    "EC2SecurityGroup": "ID",
    "EC2Subnet": None,
    "EC2VPC": "ID",
    "ECSCapacityProvider": "ARN",
    "ElasticacheCacheParameterGroup": "GroupName",
    "ElasticacheUser": "ID",
    "ElasticacheUserGroup": "ID",
    "IAMRole": "Name",
    "IAMSAMLProvider": "ARN",
    "KMSAlias": "Name",
    "MediaConvertQueue": None,
    "MemoryDBACL": "Name",
    "MemoryDBParameterGroup": "Name",
    "MemoryDBUser": "Name",
    "OSPackage": "PackageID",
    "ResourceExplorer2Index": "ARN",
    "ResourceExplorer2View": "ARN",
    "Route53HostedZone": "ID",
    "Route53ResolverFirewallDomainList": "Arn",
    "Route53ResolverRule": "ID",
}
GLOBAL_TYPES = {
    "BudgetsBudget", "CloudFrontResponseHeadersPolicy", "IAMRole",
    "IAMRolePolicyAttachment", "IAMSAMLProvider", "Route53HostedZone",
    "Route53ResourceRecordSet",
}


def has_builtin_protection(resource):
    if resource["status"] != "filtered":
        return False
    if resource["type"] == "AppStreamImage":
        return resource["reason"] == "cannot delete public AWS images"
    if resource["type"] == "CodePipelineCustomActionType":
        owner = resource.get("prop:Owner")
        return (
            owner in {"AWS", "ThirdParty"}
            and resource["reason"] == "cannot delete default codepipeline custom action type"
        )
    if resource["type"] == "Route53ResourceRecordSet":
        record_type = resource.get("prop:Type")
        return (
            record_type == "SOA" and resource["reason"] == "cannot delete SOA record"
        ) or (
            record_type == "NS"
            and resource.get("prop:Name")
            and resource["prop:Name"] == resource.get("prop:HostedZoneName")
            and resource["reason"] == "cannot delete NS record"
        )
    return False


def read_config(path, account_id):
    with path.open(encoding="utf-8") as source:
        config = yaml.safe_load(source)
    if not isinstance(config, dict):
        raise InventoryError("Scan config must be a YAML mapping.")
    accounts = config.get("accounts")
    if not isinstance(accounts, dict) or set(accounts) != {account_id}:
        raise InventoryError("Scan config must contain only the expected account.")
    regions = config.get("regions")
    if not isinstance(regions, list) or not regions or any(
        not isinstance(region, str) or not region.strip() for region in regions
    ):
        raise InventoryError("Scan config must contain a non-empty regions list.")
    return config


def read_scan_regions(path, account_id):
    return read_config(path, account_id)["regions"]


def make_cleanup_config(inventory, config):
    """Protect every entry by an exact identity or verified built-in exception."""
    if inventory["aws_nuke_version"] != "v3.68.3":
        raise InventoryError("Cleanup matching rules are verified only for aws-nuke v3.68.3.")
    if not inventory["complete"]:
        raise InventoryError("Unexpected listing errors prevent cleanup generation.")
    if sorted(set(config["regions"])) != inventory["scope"]["regions"]:
        raise InventoryError("Cleanup regions must match the baseline scan scope.")
    if not inventory["resources"]:
        raise InventoryError("Cannot generate cleanup exclusions from an empty baseline.")
    cleanup = json.loads(json.dumps(config))
    account = cleanup["accounts"][inventory["account_id"]]
    if not isinstance(account, dict):
        raise InventoryError("Account configuration must be a mapping.")
    unverified = {resource_type for resource_type, _ in EXPECTED_LISTING_ERRORS}
    unverified.update(error["resource_type"] for error in inventory["scan_errors"])
    filters = account.setdefault("filters", {})
    if not isinstance(filters, dict):
        raise InventoryError("Account filters must be a mapping.")
    if account.get("presets") or filters.get("__global__"):
        raise InventoryError("Cleanup generation requires no account presets or global filters.")
    for resource_type, existing in filters.items():
        if not isinstance(existing, list) or any(
            not isinstance(item, (str, dict)) or (
                isinstance(item, dict) and item.get("group")
            ) for item in existing
        ):
            raise InventoryError(f"Existing filters for {resource_type} must be ordinary ungrouped filters.")
    if filters.get("IAMRolePolicyAttachment"):
        raise InventoryError("Existing IAMRolePolicyAttachment filters cannot be combined with generated groups.")

    exceptions = []
    attachments = {}
    seen = set()
    regional_scope = set(config["regions"]) - {"global"}
    for resource in inventory["resources"]:
        resource_type = resource["type"]
        label = f"{resource_type} / {resource['owner']} / {resource['name']}"
        if has_builtin_protection(resource):
            exceptions.append({
                key: resource[key] for key in ("type", "name", "owner", "reason")
            })
            continue
        if resource_type == "IAMRolePolicyAttachment":
            if resource["owner"] != "global":
                raise InventoryError(f"Expected global IAM attachment scope for {label}.")
            role = resource.get("prop:RoleName")
            policy = resource.get("prop:PolicyArn")
            if not isinstance(role, str) or not role or not isinstance(policy, str) or not policy:
                raise InventoryError(f"No complete role/policy identity for {label}.")
            identity = (resource_type, role, policy)
            attachments.setdefault(role, set()).add(policy)
        else:
            if resource_type not in EXACT_PROPERTIES:
                raise InventoryError(f"No verified exact matching rule or built-in exception for {label}.")
            if (resource_type in GLOBAL_TYPES) != (resource["owner"] == "global"):
                raise InventoryError(f"Unexpected global/regional scope for {label}.")
            prop = EXACT_PROPERTIES[resource_type]
            value = resource.get(f"prop:{prop}") if prop else resource["name"]
            if not isinstance(value, str) or not value:
                raise InventoryError(f"Missing exact identity property {prop!r} for {label}.")
            # Regional names/IDs are not region-qualified by ordinary filters.
            if resource_type not in GLOBAL_TYPES and prop not in {"ARN", "Arn"}:
                if "all" in regional_scope or regional_scope != {resource["owner"]}:
                    raise InventoryError(f"Exact matching for {label} requires a single explicit regional scope.")
            identity = (resource_type, value)
            existing = filters.setdefault(resource_type, [])
            entry = {"type": "exact", "value": value}
            if prop:
                entry = {"property": prop, **entry}
            existing.append(entry)
        if identity in seen:
            raise InventoryError(f"Ambiguous duplicate exact identity for {label}.")
        seen.add(identity)

    if attachments:
        # (role in baseline roles) AND, for each role,
        # (role != this role OR policy in this role's baseline policies).
        # This preserves pairs without creating role/policy cross-products.
        grouped = []
        for index, (role, policies) in enumerate(sorted(attachments.items()), start=1):
            grouped.append({
                "group": "baseline-roles", "property": "RoleName",
                "type": "exact", "value": role,
            })
            group = f"baseline-role-{index}"
            grouped.append({
                "group": group, "property": "RoleName",
                "type": "exact", "value": role, "invert": True,
            })
            grouped.extend({
                "group": group, "property": "PolicyArn",
                "type": "exact", "value": policy,
            } for policy in sorted(policies))
        filters["IAMRolePolicyAttachment"] = grouped

    for scope in (cleanup, account):
        limits = scope.setdefault("resource-types", {})
        if not isinstance(limits, dict):
            raise InventoryError("resource-types must be a mapping.")
        for key in ("includes", "targets", "excludes", "cloud-control", "alternatives"):
            if key in limits and (
                not isinstance(limits[key], list)
                or any(not isinstance(value, str) for value in limits[key])
            ):
                raise InventoryError(f"resource-types.{key} must be a list of strings.")
        if limits.get("alternatives") or limits.get("cloud-control"):
            raise InventoryError("Cloud Control alternatives need separate baseline matching verification.")
        limits["excludes"] = sorted(set(limits.get("excludes", [])) | unverified)
        limits.pop("cloud-control", None)
        limits["alternatives"] = []

    protection = {
        "exact_match_count": len(seen),
        "builtin_protection_count": len(exceptions),
        "requires_filter_groups": bool(attachments),
        "builtin_protection": exceptions,
    }
    return cleanup, protection


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Use a complete, trusted dry-run log captured with --json --no-prompt, "
            "including stderr, without --quiet. Check the scan exit status first. "
            "Account and regions must be verified separately. complete means no "
            "unexpected listing errors; listing_complete means no listing errors. "
            "Expected failures still leave coverage gaps. This is not a deletion plan."
        ),
    )
    parser.add_argument("input", type=Path, help="Saved JSON Lines scan log")
    parser.add_argument("output", type=Path, help="YAML inventory file; replaces existing output")
    parser.add_argument(
        "--errors-output", type=Path,
        help="Unexpected errors only; removes old report if none; defaults to scan-errors.yaml beside the inventory",
    )
    parser.add_argument("--account-id", required=True, help="Account verified using STS")
    parser.add_argument(
        "--cleanup-output", type=Path,
        help="Generate a conservative draft aws-nuke config; requires --config",
    )
    parser.add_argument(
        "--account-name", default="test",
        help="Human-readable account label (default: test; workflows can supply another label)",
    )
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--config", type=Path, help="Original aws-nuke scan config")
    scope.add_argument(
        "--region", action="append",
        help="Region from the scan config; repeat for multiple regions, or use all",
    )
    args = parser.parse_args()
    if args.cleanup_output and not args.config:
        parser.error("--cleanup-output requires --config")
    errors_output = args.errors_output or args.output.with_name("scan-errors.yaml")
    staged = []
    cleanup_attempted = False
    try:
        paths = [path.resolve() for path in (args.input, args.output, errors_output)]
        if args.cleanup_output:
            paths.append(args.cleanup_output.resolve())
        if len(set(paths)) != len(paths) or (
            args.config and args.config.resolve() in paths
        ):
            raise InventoryError("Input, inventory, and error file paths must be different.")
        config = read_config(args.config, args.account_id) if args.config else None
        regions = config["regions"] if config else args.region
        with args.input.open(encoding="utf-8") as source:
            inventory = convert_inventory(
                source, args.account_id, regions, args.account_name
            )
        cleanup = None
        if args.cleanup_output and inventory["complete"]:
            cleanup_attempted = True
            cleanup, inventory["cleanup_protection"] = make_cleanup_config(inventory, config)
        errors = inventory.pop("scan_errors")
        inventory["scan_error_count"] = (
            inventory["expected_listing_error_count"] + inventory["unexpected_listing_error_count"]
        )
        inventory["scan_errors_file"] = os.path.relpath(
            errors_output.resolve(), args.output.resolve().parent
        ) if errors else None
        error_report = {
            key: inventory[key]
            for key in (
                "schema_version", "account_id", "account_name", "scan_time", "scope",
                "scan_error_count", "expected_listing_error_count",
                "unexpected_listing_error_count",
            )
        }
        error_report["scan_errors"] = errors
        documents = [(errors_output, dump_yaml(error_report))] if errors else []
        documents.append((args.output, dump_yaml(inventory)))
        if cleanup:
            documents.append((
                args.cleanup_output,
                "# Review account, blocklist, exclusions, and dry-run before deletion.\n"
                + (
                    "# REQUIRED: run with --feature-flag filter-groups for exact IAM attachment pairs.\n"
                    if inventory["cleanup_protection"]["requires_filter_groups"] else ""
                )
                + dump_yaml(cleanup),
            ))
        for path, document in documents:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=path.parent,
                prefix=f".{path.name}.", suffix=".tmp", delete=False,
            ) as destination:
                staged.append((Path(destination.name), path))
                destination.write(document)
        for temporary, path in staged:
            os.replace(temporary, path)
        if not errors:
            errors_output.unlink(missing_ok=True)
        if args.cleanup_output and not cleanup:
            args.cleanup_output.unlink(missing_ok=True)
    except (InventoryError, OSError, UnicodeError, yaml.YAMLError) as error:
        for temporary, _ in reversed(staged):
            try:
                temporary.unlink(missing_ok=True)
            except OSError as cleanup_error:
                print(f"WARNING: Could not remove temporary output {temporary}: {cleanup_error}")
        if cleanup_attempted:
            try:
                args.cleanup_output.unlink(missing_ok=True)
            except OSError as cleanup_error:
                print(f"WARNING: Could not remove invalidated cleanup output: {cleanup_error}")
        parser.exit(1, f"Inventory conversion failed: {error}\n")
    print(f"Saved {inventory['summary']['total']} resources to {args.output}")
    if args.cleanup_output:
        if cleanup:
            print(f"Saved draft cleanup config to {args.cleanup_output}")
            protection = inventory["cleanup_protection"]
            print(
                f"Baseline protection: {protection['exact_match_count']} exact matches; "
                f"{protection['builtin_protection_count']} built-in exceptions (listed in inventory)."
            )
            if protection["requires_filter_groups"]:
                print("REQUIRED: Run cleanup dry-runs and cleanup with --feature-flag filter-groups.")
            print("WARNING: Known failed-listing types remain excluded from cleanup.")
        else:
            print("WARNING: Unexpected listing errors; no cleanup config retained.")
    if errors:
        print(f"Saved {len(errors)} unexpected listing failures to {errors_output}")
    else:
        print("No unexpected listing failures; no error report retained.")
    if not inventory["complete"]:
        print(
            f"WARNING: {inventory['unexpected_listing_error_count']} unexpected listing "
            "failures recorded."
        )
    if not inventory["listing_complete"]:
        print(
            "WARNING: One or more resource listings failed; the inventory does not "
            "cover all resource types and must not be treated as a complete baseline."
        )


if __name__ == "__main__":
    main()
