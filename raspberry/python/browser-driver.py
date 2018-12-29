import json 
import pyautogui
import paho.mqtt.client as mqtt


# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("ctrl/+")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic+" "+str(msg.payload))
    index = msg.topic.find('ctrl/') ;
    if index == -1:
        return ;
    scope = msg.topic[index+5:] ;
    print("Scope = " + scope) ;
    if scope == "quit":
        quit() ;
    try:
        command = json.loads(msg.payload)
        if scope == "move":
            pyautogui.moveTo(command[u'x'], command[u'y']) ;
        elif scope == "drag":
            pyautogui.moveTo(command[u'dx'], command[u'dy']) ;
        elif scope == "scroll":
            pyautogui.scroll(command[u'scroll']) ;
        elif scope == "click":
            pyautogui.click() ;
        elif scope == "text":
            pyautogui.typewrite(command[u'text']) ;
        elif scope == "press":
            pyautogui.typewrite(command[u'key']) ;
    except:
        print("Bad formed JSON received: " + msg.payload) ;

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect("127.0.0.1", 1883, 60)

# Blocking call that processes network traffic, dispatches callbacks and
# handles reconnecting.
# Other loop*() functions are available that give a threaded interface and a
# manual interface.
client.loop_forever()
