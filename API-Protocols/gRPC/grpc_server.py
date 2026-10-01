import os
import time
from concurrent import futures
import grpc
import greeter_pb2
import greeter_pb2_grpc

API_TOKEN = os.getenv("API_TOKEN", "YOUR_TOKEN")


class AuthInterceptor(grpc.ServerInterceptor):
    def __init__(self):
        def deny(request, context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Unauthorized")

        self._deny_handler = grpc.unary_unary_rpc_method_handler(deny)

    def intercept_service(self, continuation, handler_call_details):
        metadata = dict(handler_call_details.invocation_metadata)
        if metadata.get("authorization") == f"Bearer {API_TOKEN}":
            return continuation(handler_call_details)
        return self._deny_handler


class GreeterService(greeter_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        if not request.name.strip():
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "name must not be empty")
        return greeter_pb2.HelloReply(message=f"Hello, {request.name.strip()}!")

    def StreamGreetings(self, request, context):
        if not request.name.strip():
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "name must not be empty")
        for greeting_index in range(3):
            if not context.is_active():
                return
            yield greeter_pb2.HelloReply(
                message=f"Greeting {greeting_index + 1} for {request.name.strip()}"
            )
            time.sleep(0.5)


def serve():
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        interceptors=[AuthInterceptor()],
    )
    greeter_pb2_grpc.add_GreeterServicer_to_server(GreeterService(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print("gRPC server on :50051")
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(grace=5)


if __name__ == "__main__":
    serve()