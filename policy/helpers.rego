package helpers

# オブジェクトにフィールドが存在するかを確認する関数
has_field(object, field) {
	object[field]
}

has_field(object, field) {
	object[field] == false
}

has_field(object, field) := false {
	not object[field]
	not object[field] == false
}
