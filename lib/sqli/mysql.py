from request import Request

__FILENAME__ = "mysql/errors.txt"

class MYSQL:
	def error_check(self):
		with open(__FILENAME__) as errors:
			for payloads in errors.readlines():
				print(payload)

mysql = MYSQL()
mysql.error_check()