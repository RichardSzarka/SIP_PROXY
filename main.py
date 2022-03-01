import siplib


if __name__ == "__main__":

    try:
        HOST = input("Zadajte IP proxy servera: ")
        PORT = int(input("Zadajte PORT na server: "))

        siplib.recordroute = "Record-Route: <sip:%s:%d;lr>" % (HOST, PORT)
        siplib.topvia = "Via: SIP/2.0/UDP %s:%d" % (HOST, PORT)
        siplib.topvia = bytes(siplib.topvia, "utf8")

        server = siplib.socketserver.UDPServer((HOST, PORT), siplib.UDPHandler)
    except:
        print("Socket binding sa nepodaril (asi sa port používa alebo ste zadali zlu IP)")
        exit(1)

    try:
        print("Server beží")
        server.serve_forever()
    except:
        print("Server sa vypol")
