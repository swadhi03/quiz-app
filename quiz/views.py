from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User, Role, Permission, Category, Quiz
from .serializers import UserSignupSerializer, UserSerializer, RoleSerializer, PermissionSerializer, StudentSignupSerializer, CategorySerializer, QuizSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .permissions import IsTeacherOrAdmin, IsAdmin, IsVerifiedStudent

class RoleListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        roles = Role.objects.all()
        serializer = RoleSerializer(roles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class PermissionListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        permissions_qs = Permission.objects.all()
        serializer = PermissionSerializer(permissions_qs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

# JWT Login View (Email-based)
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = User.EMAIL_FIELD

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class UserCRUDView(APIView):
    """
    Class-based view for Users with GET, POST, PUT, DELETE.
    """

    permission_classes = [permissions.IsAuthenticated]  # Only authenticated users can access

    def get(self, request, user_id=None):
        if user_id:
            try:
                user = User.objects.get(id=user_id, is_deleted=False)
                serializer = UserSerializer(user)
            except User.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            users = User.objects.all()
            serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = UserSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "message": "User created successfully",
            "user": UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)

    # -------------------------------
    # PUT: update existing user by id
    # -------------------------------
    def put(self, request, user_id=None):
        if not user_id:
            return Response({"error": "User ID is required for update"}, status=status.HTTP_400_BAD_REQUEST)
        
        if request.user.id != user_id:
            return Response({"error": "You are not allowed to update another user's profile"},
                        status=status.HTTP_403_FORBIDDEN)
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserSignupSerializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        updated_user = serializer.save()
        return Response({
            "message": "User updated successfully",
            "user": UserSerializer(updated_user).data
        }, status=status.HTTP_200_OK)

    def delete(self, request, user_id=None):
        if not user_id:
            return Response({"error": "User ID is required for deletion"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(id=user_id)
            user.is_deleted = True
            user.save()
            return Response({"message": "User deleted successfully"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

class StudentSignupView(generics.CreateAPIView):
    serializer_class = StudentSignupSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        student = serializer.save()
        return Response({
            "message": "Student registered successfully. Wait for teacher verification.",
            "student": UserSerializer(student).data
        }, status=status.HTTP_201_CREATED)
    
class VerifyStudentView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, student_id):
        if request.user.role.name == "Student" and not request.user.is_verified:
            return Response({"error: Wait for teacher verfication"}, status=403)
        # check if request.user is a teacher
        if not request.user.role or request.user.role.name != "Teacher":
            return Response({"error": "Only teachers can verify students."}, status=403)
        try:
            student = User.objects.get(id=student_id, role__name='Student')
        except User.DoesNotExist:
            return Response({"error": "Student not found"}, status=404)
        
        student.is_verified = True
        student.save()
        return Response({"message": f"{student.full_name} has been verified."}, status=200)
    
class StudentListView(generics.ListAPIView):
    queryset = User.objects.filter(role__name="Student")
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]  

class CategoryListCreateView(generics.ListCreateAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

    def get_permissions(self):
        if self.request.method == 'GET':
            return [permissions.IsAuthenticated()]  # All authenticated users
        return [IsTeacherOrAdmin()]  # Teacher/Admin only


class CategoryUpdateDeleteView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

    def get_permissions(self):
        if self.request.method in ['PUT', 'PATCH']:
            return [permissions.IsAuthenticated(), IsTeacherOrAdmin()]  # Teacher/Admin
        return [permissions.IsAuthenticated(), IsAdmin()]  # Admin only for DELETE
    
    def perform_destroy(self, instance):
        instance.is_deleted = True
        instance.save()

class QuizListCreateView(generics.ListCreateAPIView):
    queryset = Quiz.objects.filter(is_deleted=False)
    serializer_class = QuizSerializer

    def get_permissions(self):
        if self.request.method == 'GET':
            return [IsVerifiedStudent()]
        return [IsTeacherOrAdmin()]
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

class QuizDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset =Quiz.objects.filter(is_deleted = False)
    serializer_class = QuizSerializer

    def get_permissions(self):
        if self.request.method in ['PUT','PATCH']:
            return [IsTeacherOrAdmin()]
        elif self.request.method == 'DELETE':
            return [IsAdmin()]
        return [IsVerifiedStudent()]
    def perform_destroy(self, instance):
        instance.is_deleted = True
        instance.save()

