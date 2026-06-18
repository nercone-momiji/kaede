from . import Server, Callback, Response

class Demo(Callback):
    async def on_request(self, request):
        return Response("It works! This is Response from Kaede.".encode(), content_type="text/plain")

def main():
    print("Starting server... Try access it to http://localhost:80/")

    server = Server(Demo())
    server.run()

if __name__ == "__main__":
    main()
