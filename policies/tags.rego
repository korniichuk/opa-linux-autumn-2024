package policies.tags

array_contains(arr, elem) {
	arr[_] = elem
}

mandatory_tags := ["Name", "Owner"]

tag_present(tag, tags) {
	tag_value := tags[tag]
	tag_value != ""
}

deny[msg] {
	resource := input.resource_changes[_]
	action := resource.change.actions[count(resource.change.actions) - 1]
	array_contains(["create", "update"], action) # allow destroy action

	resource.type == "aws_instance"
	missing_tags := [tag | tag := mandatory_tags[_]; not tag_present(tag, resource.change.after.tags)]
	count(missing_tags) > 0

	msg := sprintf(
		"%s: Missing EC2 instance tags: %v",
		[resource.address, missing_tags],
	)
}
