import uvicorn
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

if __name__ == "__main__":
    print("Iniciando Network Scanner API...")
    print("API: http://localhost:8000")
    print("Docs: http://localhost:8000/docs")
  
    uvicorn.run(
        "src.infrastructure.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
