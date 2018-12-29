import json 
import pyautogui
import paho.mqtt.client as mqtt

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer
import urlparse


class CommandHandler:
    def process(self, command):
        try:
            action = command["action"] ;
            print "Action = " + action ;
            if action == "move":
                pyautogui.moveTo(command['x'], command['y']) ;
            elif action == "drag":
                pyautogui.moveTo(command['dx'], command['dy']) ;
            elif action == "scroll":
                pyautogui.scroll(command['scroll']) ;
            elif action == "click":
                pyautogui.click() ;
            elif action == "text":
                pyautogui.typewrite(command['text']) ;
            elif action == "press":
                pyautogui.typewrite(command['key']) ;
        except:
            print("Bad formed command: ") ;
        
handler = CommandHandler() ;
        
# Unicode to plain string dictionary conversion
def byteify(input):
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
                for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input
        

class BrowserDriverClient(object):
    def __init__(self, handler):
        self.client = mqtt.Client()
        self.handler = handler ;
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message 
    # The callback for when the client receives a CONNACK response from the server.
    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        # Subscribing in on_connect() means that if we lose the connection and
        # reconnect then subscriptions will be renewed.
        client.subscribe("ctrl/+")

    # The callback for when a PUBLISH message is received from the server.
    def on_message(self, client, userdata, msg):
        print(msg.topic+" "+str(msg.payload))
        print "Message received" ;
        try:
            command = byteify(json.loads(msg.payload)) ;
            self.handler.process(command) ;
        except:
            print("Bad formed JSON received: " + msg.payload) ;
    def start(self):
        self.client.connect("127.0.0.1", 1883, 60)
        # client.loop_forever()
        self.client.loop_start()

class SimpleServer(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
    def do_GET(self):
        parsed = urlparse.urlparse(self.path)
        #print(self.headers)
        # return None if not present
        #print(self.headers.getheader('Ciao')) ;
        #print urlparse.parse_qs(parsed.params)
        cmdlist = urlparse.parse_qs(parsed.query)
        cmd = {} ;
        for key in cmdlist:
            value = cmdlist[key][0]
            if value.isdigit():
                cmd[key] = int(value) ;
            else:
                cmd[key] = value ;
        print cmd ;
        handler.process(cmd) ;
        self._set_headers()
        self.wfile.write("OK\n")
        

client = BrowserDriverClient(handler)
client.start()

server_address = ('', 8000)
httpd = HTTPServer(server_address, SimpleServer)
print 'Starting httpd...'
httpd.serve_forever()