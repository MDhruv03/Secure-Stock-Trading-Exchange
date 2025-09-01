import matplotlib.pyplot as plt
import io
import base64

def vwap_png(prices: list, quantities: list) -> bytes:
    """Generates a VWAP chart as a PNG image."""
    if not prices or not quantities or len(prices) != len(quantities):
        # Return a placeholder or raise an error if data is invalid
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.text(0.5, 0.5, "No data available", horizontalalignment='center', verticalalignment='center', transform=ax.transAxes)
        ax.set_title("VWAP Chart")
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        plt.close(fig)
        return buf.getvalue()

    # Calculate VWAP points for plotting
    cumulative_price_qty = 0
    cumulative_qty = 0
    vwap_points = []

    for i in range(len(prices)):
        cumulative_price_qty += prices[i] * quantities[i]
        cumulative_qty += quantities[i]
        if cumulative_qty > 0:
            vwap_points.append(cumulative_price_qty / cumulative_qty)
        else:
            vwap_points.append(0) # Or handle as appropriate

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(vwap_points, marker='o', linestyle='-', color='blue')
    ax.set_title("Volume Weighted Average Price (VWAP)")
    ax.set_xlabel("Order Index")
    ax.set_ylabel("VWAP")
    ax.grid(True)

    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close(fig)
    return buf.getvalue()