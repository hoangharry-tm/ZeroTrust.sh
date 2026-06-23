from pydantic import BaseModel


class User(BaseModel):
    id: int
    username: str
    password: str
    role: str


class Product(BaseModel):
    id: int
    name: str
    description: str
    price: float


class Order(BaseModel):
    id: int
    user_id: int
    product_id: int
    quantity: int
    status: str


class ChatRequest(BaseModel):
    message: str
    user_id: int
