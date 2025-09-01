from fastapi import APIRouter, Depends, HTTPException, Request
from app.database import database
from app.security import get_current_user
from app.models import users
from app.services.ids_service import raise_alert, scan_request_for_ioc
import json

router = APIRouter()

@router.get("/vuln/unsafe_search")
async def unsafe_search(request: Request, q: str, current_user: dict = Depends(get_current_user)):
    """
    Intentionally vulnerable endpoint for demonstrating SQL injection.
    DO NOT USE IN PRODUCTION.
    """
    # Simulate IDS scanning the request
    ioc_matches = await scan_request_for_ioc(q)
    if ioc_matches:
        await raise_alert(
            alert_type="sqli",
            description=f"Potential SQL Injection detected in unsafe_search: {ioc_matches}",
            src_ip=request.client.host,
            raw=f"Query: {q}"
        )

    # Vulnerable SQL query (for demonstration purposes only)
    # In a real application, use parameterized queries to prevent SQLi
    query_str = f"SELECT username, balance FROM users WHERE username LIKE '%{q}%'"
    
    try:
        # Execute the raw SQL query
        results = await database.fetch_all(query_str)
        return {"query": query_str, "results": results}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")