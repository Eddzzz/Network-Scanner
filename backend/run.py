import uvicorn
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

if __name__ == "__main__":
    print("Iniciando Network Scanner API...")
    print("API: http://localhost:8065")
    print("Docs: http://localhost:8065/docs")
  
    uvicorn.run(
        "src.infrastructure.api:app",
        host="127.0.0.1",
        port=8065,
        reload=False
    )
