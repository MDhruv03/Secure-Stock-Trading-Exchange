from fastapi import APIRouter, Depends
from app.security import get_current_admin_user
from app.utils.demo_data import seed_demo_data

router = APIRouter()

@router.post("/demo-data")
async def generate_demo_data(current_user: dict = Depends(get_current_admin_user)):
    await seed_demo_data()
    return {"message": "Demo data generated successfully"}
