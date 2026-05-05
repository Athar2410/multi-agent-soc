import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

ef = SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
client = chromadb.PersistentClient(path="./chroma_db")

def get_log_collection():
    return client.get_or_create_collection("soc_logs", embedding_function=ef)

def get_case_collection():
    return client.get_or_create_collection("soc_cases", embedding_function=ef)

def add_log(log_text: str, metadata: dict):
    col = get_log_collection()
    import uuid
    col.add(documents=[log_text], metadatas=[metadata], ids=[str(uuid.uuid4())])

def query_logs(query: str, n=5) -> list:
    col = get_log_collection()
    results = col.query(query_texts=[query], n_results=n)
    return results["documents"][0] if results["documents"] else []