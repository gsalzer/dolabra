import logging
import os
from datetime import datetime

def setup_logger(logging_level=logging.INFO):
    logging.basicConfig(level=logging_level)
    current_time = datetime.now().strftime('%m-%d_%H-%M-%S')

    current_file_path = os.path.abspath(__file__)
    dolabra_package_path = os.path.dirname(os.path.dirname(current_file_path))
    filename = f"log_output_{current_time}.txt"
    log_directory = os.path.join(dolabra_package_path, 'logs')

    # Ensure the 'logs' directory exists
    os.makedirs(log_directory, exist_ok=True) 

    log_file_path = os.path.join(log_directory, filename)
    file_handler = logging.FileHandler(log_file_path)

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logging.getLogger().addHandler(file_handler)
