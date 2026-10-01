# API Protocol Examples
pip install -r requirements.txt

| Protocol  | Server               | Client               | Port  |
|-----------|----------------------|----------------------|-------|
| REST      | rest_server.py       | rest_client.py       | 8000  |
| SSE       | sse_server.py        | curl -N /events      | 8001  |
| GraphQL   | graphql_server.py    | graphql_client.py    | 8002  |
| WebSocket | websocket_server.py  | websocket_client.py  | 8765  |
| gRPC      | grpc_server.py       | grpc_client.py       | 50051 |

gRPC needs codegen first:
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. greeter.proto
