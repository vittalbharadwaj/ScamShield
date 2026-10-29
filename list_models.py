"""Print the model IDs your Token Factory key can use (Nemotron ones first)."""
import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI(
    api_key=os.environ["NEBIUS_API_KEY"],
    base_url=os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/"),
)
ids = sorted(m.id for m in client.models.list().data)
nemo = [i for i in ids if "nemotron" in i.lower()]
print("== Nemotron models ==")
print("\n".join(nemo) or "(none found - check the Token Factory model catalog)")
print("\n== All models ==")
print("\n".join(ids))
