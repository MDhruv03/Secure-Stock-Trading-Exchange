import requests
import json

# Test the user activity logs API endpoint
try:
    response = requests.get('http://127.0.0.1:8000/api/logs/user-activity')
    
    if response.status_code == 200:
        data = response.json()
        logs = data.get('logs', [])
        
        print(f"✓ API returned {len(logs)} user activity logs")
        print("\n" + "=" * 100)
        print(f"{'Timestamp':<25} | {'Event Type':<20} | {'Description'}")
        print("=" * 100)
        
        # Show first 20 logs
        for log in logs[:20]:
            timestamp = log.get('created_at', 'N/A')
            event_type = log.get('event_type', 'N/A')
            description = log.get('description', 'N/A')
            print(f"{timestamp:<25} | {event_type:<20} | {description}")
        
        # Count event types
        from collections import Counter
        event_counts = Counter([log['event_type'] for log in logs])
        
        print("\n" + "=" * 100)
        print("\nEvent Type Breakdown:")
        for event_type, count in event_counts.items():
            print(f"  {event_type}: {count}")
            
    else:
        print(f"✗ API request failed with status code: {response.status_code}")
        print(f"Response: {response.text}")
        
except Exception as e:
    print(f"✗ Error testing API: {str(e)}")
