import os
import strawberry
from fastapi import FastAPI
from graphql import GraphQLError
from strawberry.fastapi import GraphQLRouter
from strawberry.permission import BasePermission

API_TOKEN = os.getenv("API_TOKEN", "YOUR_TOKEN")


class IsAuthenticated(BasePermission):
    message = "Unauthorized"

    def has_permission(self, source, info, **kwargs) -> bool:
        request = info.context["request"]
        return request.headers.get("Authorization") == f"Bearer {API_TOKEN}"


@strawberry.type
class Book:
    id: int
    title: str
    author: str


book_catalog: list[Book] = [
    Book(id=1, title="Dune", author="Frank Herbert"),
    Book(id=2, title="Neuromancer", author="William Gibson"),
]


@strawberry.type
class Query:
    @strawberry.field(permission_classes=[IsAuthenticated])
    def books(self) -> list[Book]:
        return book_catalog

    @strawberry.field(permission_classes=[IsAuthenticated])
    def book(self, id: int) -> Book | None:
        return next((b for b in book_catalog if b.id == id), None)


@strawberry.type
class Mutation:
    @strawberry.mutation(permission_classes=[IsAuthenticated])
    def add_book(self, title: str, author: str) -> Book:
        if not title.strip() or not author.strip():
            raise GraphQLError("title and author must not be empty")
        new_id = max((b.id for b in book_catalog), default=0) + 1
        new_book = Book(id=new_id, title=title.strip(), author=author.strip())
        book_catalog.append(new_book)
        return new_book


app = FastAPI()
app.include_router(
    GraphQLRouter(strawberry.Schema(query=Query, mutation=Mutation)),
    prefix="/graphql",
)