from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    remember_token = Column(String, nullable=True)  # Add this field
    artworks = relationship('Artwork', back_populates='user')

class Artwork(Base):
    __tablename__ = 'artworks'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    name = Column(String, nullable=False)
    path = Column(String, nullable=False)
    signature = Column(String, nullable=True)
    public_key = Column(String, nullable=True)  # Add this field to store the public key
    user = relationship('User', back_populates='artworks')


# Create the database and tables
if __name__ == "__main__":
    from sqlalchemy import create_engine
    engine = create_engine('sqlite:///das_app.db')
    Base.metadata.create_all(engine)
    print("Database and tables created successfully.")
