require("print_r")
require("math")

print_r("Load lua message processors")

spoa.register_message("check-client-ip", function(args)
	print_r(args)
	spoa.set_var_null("null", spoa.scope.txn)
	spoa.set_var_boolean("boolean", spoa.scope.txn, true)
	spoa.set_var_int32("int32", spoa.scope.txn, 1234)
	spoa.set_var_uint32("uint32", spoa.scope.txn, 1234)
	spoa.set_var_int64("int64", spoa.scope.txn, 1234)
	spoa.set_var_uint64("uint64", spoa.scope.txn, 1234)
	spoa.set_var_ipv4("ipv4", spoa.scope.txn, "127.0.0.1")
	spoa.set_var_ipv6("ipv6", spoa.scope.txn, "1::f")
	spoa.set_var_str("str", spoa.scope.txn, "1::f")
	spoa.set_var_bin("bin", spoa.scope.txn, "1::f")
	spoa.set_var_int32("ip_score", spoa.scope.sess, math.random(100))
end)
