# Auditorium

**Opinions & Ideas — An Open Source Platform for Expression, Analysis, and Creation**

_A project by Navid Rahimzadeh_  
_“I GRIEVE DIFFERENT.”_

---

## Overview

**Auditorium** is more than just a publishing platform — it’s an **artistic, digital space** for thought, discourse, and creation. At its core, Auditorium is built on the belief that **freedom of expression** is essential to the development of meaningful dialogue. This platform invites users to write, analyze, critique, and engage — freely and deeply — with texts, ideas, and each other.

Initially developed as a blog-like system, Auditorium is evolving into a layered, structured **discussion network** powered by Python, Django, PostgreSQL, and a modern frontend stack. Fully Dockerized for portability and development, Auditorium provides a foundation for intellectual and artistic communities to grow.

---

## Project Status

**Alpha stage, ver. 00.00**  
Stage: Early Development  
**Release Date:** April 30th, 2025

---

## Key Features

- **User Publishing**: Articles, analyses, stories, critiques — users can publish and protect their written work.
- **Discussion Halls**: Structured conversation spaces (Topics) that allow for deep, nested dialogue around themes or texts.
- **Access Levels & Licensing**: Content can be marked as open for response, critique, or protected for private reflection.
- **Custom User System**: Tailored user profiles with bio, avatar, banner, and layered access levels (owner, manager, regular).
- **Projects & Releases Hall**: A separate space for users to present and deliver personal or collaborative projects.
- **Management Panel**: Dynamic user dashboards for managing contributions, privacy, and publishing permissions.
- **Dockerized Environment**: Ready-to-run containers for development, testing, and deployment.

---

## Tech Stack

- **Frontend**: HTML, CSS & JavaScript  
- **Backend**: Python & Django  
- **Database**: PostgreSQL  
- **Containerization**: Docker

---

## Getting Started

### Prerequisites

- [Docker](https://www.docker.com/)

### Setup

To setup the project, first of all you need to create the .env file based on .env.example file. 

```bash
# Clone the project
git clone https://github.com/your-username/auditorium.git
cd auditorium

# Start the Docker containers
docker-compose up --build
```

Start the application by navigating to `http://localhost:8000` in your web browser.
