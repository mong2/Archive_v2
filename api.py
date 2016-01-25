import requests

class Api:
	def __init__(self, token):
		authstring = "Bearer " + str(token)
		self.header = {
			"Authorization": authstring,
			"Content-type": "application/json"
		}
		self.base_url = "https://api.cloudpassage.com/"
		return None

	def get(self, url):
		endpoint = self.base_url + url
		resp = requests.get(endpoint, headers=self.header)
		return resp

	def post(self, url, body):
		endpoint = self.base_url + url
		resp = requests.post(endpoint, data=body, header=self.header)
		return resp

	def put(self, url, body):
		endpoint = self.base_url + url
		resp = requests.put(endpoint, data=body, header=self.header)
		return resp

	def delete(self, url):
		endpoint = self.base_url + url
		resp = requests.delete(endpoint, header=self.header)
		return resp