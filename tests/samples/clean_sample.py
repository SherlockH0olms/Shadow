"""
Clean Python Sample - Should NOT be flagged as malicious
This is a normal, legitimate Python script
"""

import json
import requests
from datetime import datetime


class WeatherAPI:
    """
    Simple weather API client
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.openweathermap.org/data/2.5"

    def get_current_weather(self, city: str) -> dict:
        """
        Fetch current weather for a city

        Args:
            city: City name

        Returns:
            Weather data dictionary
        """
        url = f"{self.base_url}/weather"
        params = {
            'q': city,
            'appid': self.api_key,
            'units': 'metric'
        }

        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error fetching weather: {e}")
            return {}

    def format_weather_report(self, weather_data: dict) -> str:
        """
        Format weather data into readable report
        """
        if not weather_data:
            return "No weather data available"

        temp = weather_data.get('main', {}).get('temp', 'N/A')
        description = weather_data.get('weather', [{}])[0].get('description', 'N/A')
        humidity = weather_data.get('main', {}).get('humidity', 'N/A')

        report = f"""
Weather Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}
================================================
Temperature: {temp}°C
Conditions: {description}
Humidity: {humidity}%
        """

        return report.strip()


def main():
    """
    Main function to demonstrate weather API usage
    """
    # Example usage
    api_key = "your_api_key_here"
    weather_client = WeatherAPI(api_key)

    # Get weather for a city
    city = "London"
    weather = weather_client.get_current_weather(city)

    # Print formatted report
    report = weather_client.format_weather_report(weather)
    print(report)

    # Save to file
    with open('weather_report.json', 'w') as f:
        json.dump(weather, f, indent=2)

    print(f"\nWeather data saved to weather_report.json")


if __name__ == "__main__":
    main()
