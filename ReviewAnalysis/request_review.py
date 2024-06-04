import json
import requests
# from bs4 import BeautifulSoup
import selenium

headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
		  'authority':'api.sidequestvr.com',
		  'Accept':'*/*',
		  'Content-Type': 'application/json',
		  'Origin':'https://sidequestvr.com',
		  'Referer':'https://sidequestvr.com/'}

with open('./urls.json','r') as f:
	urls = json.loads(f.readline())

# sorted_urls = sorted(d.items(),key = lambda item:item[1])


for url,num in urls.items():
	name = url.split('/')[-1]
	if num <= 400:
		name = str(num+500) + '-' + name
	else:
		name = str(num-400) + '-' + name
	print(name)
	colletced_reviews = []
	i = -10
	app_id = url.split('/')[-2]
	if 'oculus.com' in url:
		continue
	while True:
		i += 10
		# review_url = 'https://api.sidequestvr.com/v2/apps/270/posts?skip={}&limit=20'.format(i)
		review_url = 'https://api.sidequestvr.com/v2/apps/{}/posts?skip={}&limit=20'.format(app_id,i)
		response = requests.get(review_url)
		if response.status_code != 200:
			print("Error")
			break
		elif response.status_code == 200:
			data = response.json()
			if data == []:
				break
			for review in data:
				review_text = review['body']
				if review_text not in colletced_reviews:
					colletced_reviews.append(review_text)
	with open('./{}.txt'.format(name),'w', encoding='utf-8') as g:
		for item in colletced_reviews:
			if item == '' or item == None:
				continue
			g.write(item)
			g.write('\n')


    


