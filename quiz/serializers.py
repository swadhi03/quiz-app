from rest_framework import serializers
from .models import User, Role, Permission
import re

# Role Serializer
class RoleSerializer(serializers.ModelSerializer):
    permissions = serializers.StringRelatedField(many=True)  # show permission names

    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'permissions']

# Permission Serializer
class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'description']

# User Signup Serializer
class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6, max_length=128)
    email = serializers.EmailField()
    
    class Meta:
        model = User
        fields = ['username', 'full_name', 'email', 'password', 'role', 'student_class', 'department']

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email is already in use.")
        return value

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username is already taken.")
        return value

    def validate_password(self, value):
        
        if len(value) < 6:
            raise serializers.ValidationError("Password must be at least 6 characters long.")
        if not re.search(r"\d", value):
            raise serializers.ValidationError("Password must contain at least 1 number.")
        if not re.search(r"[A-Za-z]", value):
            raise serializers.ValidationError("Password must contain at least 1 letter.")
        return value

    def validate_role(self, value):
        if value is None:
            raise serializers.ValidationError("Role must be selected.")
        return value

    def validate(self, attrs):
        """
        Object-level validation: ensure optional fields match role.
        - student_class only for students
        - department only for teachers
        """
        role_name = attrs['role'].name.lower()
        student_class = attrs.get('student_class')
        department = attrs.get('department')

        if role_name == 'student' and not student_class:
            raise serializers.ValidationError({"student_class": "Student class is required for student role."})
        if role_name == 'teacher' and not department:
            raise serializers.ValidationError({"department": "Department is required for teacher role."})
        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

class UserSerializer(serializers.ModelSerializer):
    role_name = serializers.CharField(source='role.name', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'full_name', 'email', 'role', 'role_name', 'student_class', 'department', 'is_verified']

class StudentSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'full_name', 'email', 'password', 'student_class', 'phone']

    def create(self, validated_data):
        student_role = Role.objects.get(name='Student')  # automatically assign student role
        password = validated_data.pop('password')
        user = User(role=student_role, **validated_data)
        user.set_password(password)
        user.is_verified = False  # must be verified by teacher later
        user.save()
        return user

