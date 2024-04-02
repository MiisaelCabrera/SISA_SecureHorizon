from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
uri = "mongodb+srv://admin:Hola33..@securehrizon.xfycitu.mongodb.net/?retryWrites=true&w=majority&appName=SecureHrizon"
# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))
# Send a ping to confirm a successful connection


db = client.SecureHorizon

collection = db.mycollection

new_post = {
    "title": "Mi primer post",
    "content": "Este es el contenido de mi primer post.",
    "author": "John Doe"
}

insert_result = collection.insert_one(new_post)

print("ID del nuevo post:", insert_result.inserted_id)


try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)