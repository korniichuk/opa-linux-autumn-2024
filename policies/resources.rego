package policies.resources

array_contains(arr, elem) {
	arr[_] = elem
}

allowed_resources = [
	"aws_vpc",
	"aws_subnet",
	"aws_instance",
]

deny[msg] {
	resource := input.resource_changes[_]
	action := resource.change.actions[count(resource.change.actions) - 1]
	array_contains(["create", "update"], action) # allow destroy action

	not array_contains(allowed_resources, resource.type)

	msg := sprintf(
		"%s: resource type %q is not allowed",
		[resource.address, resource.type],
	)
}
