from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

# --------------------------
# Permissions Table
# --------------------------
class Permission(models.Model):
    """
    Stores system actions that can be assigned to roles.
    """
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


# --------------------------
# Roles Table
# --------------------------
class Role(models.Model):
    """
    Defines roles like Admin, Teacher, Student.
    Each role can have multiple permissions.
    """
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True, null=True)
    permissions = models.ManyToManyField(Permission, blank=True)

    def __str__(self):
        return self.name


# --------------------------
# Custom User Model
# --------------------------
class User(AbstractUser):
    """
    Custom user model with role reference and all fields in a single table.
    """
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Common fields
    full_name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    
    # Optional role-specific fields
    student_class = models.CharField(max_length=50, blank=True, null=True)  # For students
    department = models.CharField(max_length=100, blank=True, null=True)    # For teachers
    is_verified = models.BooleanField(default=False)  # Mainly for students

    # Timestamps
    date_joined = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    # Authentication
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'full_name']  # username still required for AbstractUser

    def __str__(self):
        return f"{self.full_name} ({self.role.name if self.role else 'No Role'})"

    # Helper method to check if user has a permission
    def has_permission(self, perm_name):
        if self.role and self.role.permissions.filter(name=perm_name).exists():
            return True
        return False
    
class Category(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        self.name

class Quiz(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='quizzez')
    created_by = models.ForeignKey('User', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        self.title

class Question(models.Model):
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='questions')
    question = models.TextField(100)
    option_a = models.CharField(max_length=50)
    option_b = models.CharField(max_length=50)
    option_c = models.CharField(max_length=50)
    option_d = models.CharField(max_length=50)
    correct_answer = models.CharField(max_length=1, choices=[
        ('A', 'Option A'),
        ('B', 'Option B'),
        ('C', 'Option C'),
        ('D', 'Option D')
    ])
    marks = models.IntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.question_text[:50]}..."
    

