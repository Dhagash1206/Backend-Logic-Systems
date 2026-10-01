import grpc
import greeter_pb2
import greeter_pb2_grpc

TOKEN = "YOUR_TOKEN"
metadata = [("authorization", f"Bearer {TOKEN}")]

try:
    with grpc.insecure_channel("localhost:50051") as channel:
        grpc.channel_ready_future(channel).result(timeout=5)
        stub = greeter_pb2_grpc.GreeterStub(channel)
        request = greeter_pb2.HelloRequest(name="Asha")

        reply = stub.SayHello(request, timeout=10, metadata=metadata)
        print(reply.message)

        for streamed_reply in stub.StreamGreetings(request, timeout=10, metadata=metadata):
            print(streamed_reply.message)

except grpc.FutureTimeoutError:
    print("Could not connect to server")
except grpc.RpcError as e:
    print("RPC failed:", e.code(), e.details())