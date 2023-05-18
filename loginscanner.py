import click
import requests
import re
import json
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from urllib.parse import urljoin
from flask import Flask, render_template, request
from flask_socketio import SocketIO,emit,join_room,leave_room





def spider_website(url, max_depth,timeout):
    visited_urls = set()
    urls_to_visit = [(url, 0)]  # (url, depth)

    while urls_to_visit:
        current_url, current_depth = urls_to_visit.pop()
        if current_url in visited_urls or current_depth > max_depth:
            continue

        try:
            response = requests.get(current_url, timeout=1)
            if response.status_code != 200:
                continue

            visited_urls.add(current_url)

            links = extract_links(current_url, response.text)
            for link in links:
                if link not in visited_urls:
                    urls_to_visit.append((link, current_depth + 1))

        except KeyboardInterrupt as Ki:
            sys.exit(0)
        except Exception as e:
            print(e.message)

    return visited_urls
def extract_links(url, content):
    soup = BeautifulSoup(content, "html.parser")
    links = []

    for link in soup.find_all("a"):
        href = link.get("href")
        if href:
            full_url = urljoin(url, href)
            links.append(full_url)

    return links
def detect_login_form(html):
    score = 0
    soup = html
    forms = soup.find_all("form")

    form_keywords = ["login", "signin", "log-in", "sign-in", "auth", "authentication", "session"]
    input_keywords = ["username", "user", "email", "password", "pass", "pwd"]

    for form in forms:
        for keyword in form_keywords:
            if keyword in form.get("id", "").lower() or keyword in " ".join(form.get("class", [])).lower() or keyword in form.get("name", "").lower():
                score += 1

        form_str = str(form).lower()
        for keyword in input_keywords:
            if keyword in form_str:
                score += 1

        email_pattern = re.compile(r'<input[^>]*type=["\']?email["\']?[^>]*>', re.IGNORECASE)
        password_pattern = re.compile(r'<input[^>]*type=["\']?password["\']?[^>]*>', re.IGNORECASE)

        form_str = str(form)
        if email_pattern.search(form_str):
            score += 2
        if password_pattern.search(form_str):
            score += 20

    return score


def check_url(url, spider, max_depth, timeout=1,proxy=None):
    
    if spider:
        visited_urls = spider_website(url, max_depth,timeout)
    else:
        visited_urls = [url]

    for visited_url in visited_urls:
        try:
            response = requests.get(visited_url, timeout=timeout,proxies=proxy)
            if response.status_code != 200:
                continue
            soup = BeautifulSoup(response.text, "html.parser")
            score = detect_login_form(soup)
            if score > 1:
                return visited_url, score

        except KeyboardInterrupt as Ki:
            sys.exit(0)
        except Exception as e:
            print(e.message)

    return url, 0



def perform_login_detection(websites=None,single_url=None,wordlist=None,threads=100,output=False,max_depth=2,timeout=1,spider=False,proxy=None,client_sid=None,extension=None):
    
    if wordlist is None:
        wordlist=open("./raft","r")
    wordlist = [line.strip() for line in wordlist.readlines()]
    
    #print(wordlist)
    
    if extension:
        new_wordlist=[]
        extensions=extension.split()
        for word in wordlist:
            new_wordlist.append(word)
            for x in extensions:
                new_wordlist.append(f"{word}.{x}")
    
        wordlist=new_wordlist
    wordlist.append("")
    base_urls=[]
    if single_url:
        base_urls = [single_url]
    else:
        try:
            base_urls = [line.strip() for line in websites.readlines()]
        except AttributeError:
            print("Probably running as a server")
            base_urls=websites
    print(f"base_url={base_urls}")

    urls_to_check = []
    for base_url in base_urls:
        for word in wordlist:
            url = urljoin(base_url, word)
            urls_to_check.append(url)
    #print(f"urls_to_check={urls_to_check}")
    results = {}
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(check_url, url, spider, max_depth, timeout,proxy): url for url in urls_to_check}
        if client_sid:
            size=len(urls_to_check)
            count=0
            
        with click.progressbar(length=len(urls_to_check), label="Scanning websites") as bar:
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    visited_url, score = future.result()
                    if score > 0:
                        results[visited_url] = score
                except KeyboardInterrupt as Ki:
                    sys.exit(0)
                except Exception as e:
                    pass
                if client_sid:
                    count+=1
                    #print("sending progress")
                    if count%5==0:
                        socketio.emit("scan_progress",{'progress': count/size*100,'results':results},room=client_sid)

                bar.update(1)
    if output:

        with open(output, "w") as outfile:
            json.dump(results, outfile)
        click.echo(f"Results saved to {output}")
    click.echo(results)
    return results
@click.command()
@click.option("--websites","-f", type=click.File("r"), help="File containing list of websites to scan.")
@click.option("--single-url","-u", type=str, help="A single URL to scan.")
@click.option("--wordlist","-w", type=click.File("r"), help="File containing list of words to check.")
@click.option("--threads", type=int, default=100, help="Number of concurrent threads.")
@click.option("--output", "-o",type=str, help="Output file to store the results as JSON.")
@click.option("--max-depth", type=int, default=2, help="Maximum depth to follow links during spidering.")
@click.option("--timeout","-t", type=float, default=0.7, help="Timeout in seconds for requests.")
@click.option("--spider", is_flag=True, help="Enable spidering functionality.")
@click.option("--proxy","-p", type=str, help="Proxy to run the requests through")
@click.option('--server', is_flag=True, help='Run the script as an API server')
@click.option("--extension","-x",default=None,type=str,help="Space-separated values of extensions eg php html.")
def main(websites, single_url, wordlist, threads, output, max_depth, timeout, spider,proxy,server,extension):
    if server:

        socketio.run(app, debug=True)
    else: 
        perform_login_detection(websites,single_url,wordlist,threads,output,max_depth,timeout,spider,proxy,extension=extension)

app = Flask(__name__)
socketio = SocketIO(app)
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/scan', methods=['POST'])
def scan():
    # Extract input parameters from the request
    websites = request.form.get('websites').splitlines()
    wordlist = request.form.get('wordlist')
    use_spider = request.form.get('use_spider') == 'on'
    proxy = request.form.get('proxy')
    # Call the login interface detection function with the input parameters
    # You may need to modify the function to return results as JSON
    results = perform_login_detection(websites, wordlist, use_spider, proxy)
    return results
@socketio.on('start_scan')
def handle_start_scan(data):
    client_sid=request.sid
    print(client_sid)
    websites = data.get('websites', '').split("\n")
    use_spider = data.get('use_spider', False)
    proxy = data.get('proxy', '')
    print(f"got here, websites={websites},{type(websites)}")
    results = perform_login_detection(websites=websites, spider=use_spider, proxy=proxy,client_sid=client_sid)
    results = list(results.keys())
    emit('scan_complete', results)
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    room = request.sid  # Use the session ID as the unique room identifier
    join_room(room)
    emit('room_joined', {'room': room})  # Inform the client about the room

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
    room = request.sid
    leave_room(room)
if __name__ == "__main__":
    main()

