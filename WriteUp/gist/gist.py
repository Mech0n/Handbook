import requests
import asyncio
import wget
import os

user = 'Mech0n' # Your Username
api = 'https://api.github.com/users/%s/gists' % (user)
user_agent = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.104 Safari/537.36 Core/1.53.4295.400 QQBrowser/9.7.12661.400'
header = {'User-Agent':user_agent}

# get json
proxies = { # need proxy
  'http' : 'http://127.0.0.1:1087',
  'https' : 'http://127.0.0.1:1087'
}
r = requests.get(api, proxies=proxies, headers=header, verify=False)

if r.status_code is not 200 :
  print("Error : Can't connect to Gist!")
  exit(-1)

all_list = r.json()

# get exp dict, like {'exp.py' : 'url'}
exp_list = []
for element_dict in all_list:
  file_dict = element_dict['files']
  for file_values in file_dict.values():
    exp_list.append([file_values['filename'], file_values['raw_url']])

# download exp
async def wget_exp(url, filename):
  if os.path.exists(filename):
    return '\n%s is exist!' % (filename)
  print('\nDonwload %s...' % (filename))
  wget.download(url, out=filename)
  return '\nDownload %s Complete!' % (filename)

async def main_wget(exp_list):
  res = [wget_exp(exp_element[1], exp_element[0]) for exp_element in exp_list]
  downloaded, downloading = await asyncio.wait(res)
  for i in downloaded:
    print(i.result())

eventLoop = asyncio.get_event_loop()
eventLoop.run_until_complete(main_wget(exp_list))

# wget $(curl https://api.github.com/users/mech0n/gists | grep -o -e "https://gist\.githubu\S*" | sed 's/",//g')