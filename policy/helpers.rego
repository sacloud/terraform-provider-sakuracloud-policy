package helpers
import rego.v1

# オブジェクトにフィールドが存在するかを確認する関数
has_field(object, field) if {
	object[field]
}

has_field(object, field) if {
	object[field] == false
}
