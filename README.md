# Digital Art Signature

**Digital Art Signature** is a Python desktop application that allows users to register, login, upload artworks, digitally sign them using DSA (Digital Signature Algorithm), and verify those signatures. The app is built with `customtkinter` for a modern, stylish GUI and uses `SQLAlchemy` for database management.

## Features

- **User Authentication**: Register and login securely with hashed passwords.
- **Artwork Upload & Display**: Upload digital artwork and view them within the app.
- **Digital Signing**: Securely sign uploaded artworks using DSA.
- **Signature Verification**: Verify the digital signature of artworks.
- **"Remember Me" Functionality**: Users can stay logged in across sessions with a "Remember Me" token.
- **Logout Functionality**: Log out to switch users or return to the welcome page.

## Installation

### Prerequisites

Before you begin, ensure you have met the following requirements:

- Python 3.8 or higher
- Required Python packages (see [requirements.txt](./requirements.txt))

### Steps

1. **Clone the repository**:

   ```bash
   git clone https://github.com/saltyma/DigitalArtSignature.git


2. **Navigate to the project directory**:
    ```bash
    cd DigitalArtSignature


3. **Install the required dependencies**:
    ```bash
    pip install -r requirements.txt


4. **Run the database creation script** (this is only necessary the first time to set up the database):
    ```bash
    python create_database.py


5. **Start the application**:
    ```bash
    python app.py


## Usage
1. **Register a New User**: Click on "Register" and create a new account.
2. **Login**: Enter your username and password, or check "Remember Me" to stay logged in across sessions.
3. **Upload Artwork**: After logging in, upload your artwork files.
4. **Sign Artwork**: Digitally sign your artwork and view the associated signature.
5. **Verify Signature**: Go to the artwork details page to verify the signature's authenticity.
