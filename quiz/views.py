from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User, Role, Permission, Category, Quiz, Question, AnswerSubmission, QuizAttempt
from .serializers import UserSignupSerializer, UserSerializer, RoleSerializer, PermissionSerializer, StudentSignupSerializer, CategorySerializer, QuizSerializer, QuestionSerializer, StudentQuestionSerializer, QuizAttemptSerializer, QuizAttemptCreateSerializer, AnswerSubmissionSerializer, AnswerSubmitSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .permissions import IsTeacherOrAdmin, IsAdmin, IsVerifiedStudent
from django.shortcuts import get_object_or_404
from quiz import serializers
from rest_framework.exceptions import ValidationError
from django.core.mail import send_mail
from django.conf import settings

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

class QuestionListCreateView(generics.ListCreateAPIView):
    serializer_class = QuestionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = Question.objects.filter(is_deleted=False)
        quiz_id = self.request.query_params.get('quiz_id')  # ?quiz_id=1
        if quiz_id:
            queryset = queryset.filter(quiz_id=quiz_id)
        return queryset

    def get_serializer_class(self):
        user = self.request.user
        if hasattr(user, 'role') and user.role.name.lower() == 'student':
            return StudentQuestionSerializer  # hides correct_answer, created_at, updated_at
        return QuestionSerializer

    def get_permissions(self):
        if self.request.method == 'GET':
            return [permissions.IsAuthenticated()]  # any logged-in user can view
        return [IsTeacherOrAdmin()]  # only teacher/admin can create
    

# Retrieve, Update, Delete Question
class QuestionDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Question.objects.filter(is_deleted=False)
    serializer_class = QuestionSerializer

    def get_permissions(self):
        if self.request.method in ['PUT', 'PATCH']:
            return [IsTeacherOrAdmin()]
        elif self.request.method == 'DELETE':
            return [IsAdmin()]
        return [permissions.IsAuthenticated()]

    def perform_destroy(self, instance):
        instance.is_deleted = True
        instance.save()

class QuizAttemptStartView(generics.CreateAPIView):
    queryset = QuizAttempt.objects.all()
    serializer_class = QuizAttemptCreateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        quiz = serializer.validated_data.get('quiz')
        existing_attempt = QuizAttempt.objects.filter(
            student=self.request.user, quiz=quiz, completed_at__isnull=True
        ).first()
        if existing_attempt:
            raise ValidationError("You already have an active attempt for this quiz.")
        serializer.save(student=self.request.user, quiz=quiz)


# Submit quiz answers
class QuizSubmitView(generics.GenericAPIView):
    serializer_class = AnswerSubmitSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        attempt_id = serializer.validated_data['attempt_id']
        answers = serializer.validated_data['answers']

        attempt = get_object_or_404(QuizAttempt, id=attempt_id, student=request.user)

        for ans in answers:
            question_id = ans.get('question_id')
            selected_option = ans.get('selected_option')

            # Ensure question belongs to the same quiz
            question = get_object_or_404(Question, id=question_id, quiz_id=attempt.quiz.id)

            is_correct = (
                selected_option.strip().lower() == question.correct_answer.strip().lower()
            )

            AnswerSubmission.objects.create(
                attempt=attempt,
                question=question,
                selected_option=selected_option,
                is_correct=is_correct
            )

        # Update score after all answers processed
        attempt.calculate_score()

        return Response({
            "message": "Answers submitted successfully",
            "score": attempt.score
        })


# View all quiz attempts of the logged-in user
class MyQuizAttemptsView(generics.ListAPIView):
    serializer_class = QuizAttemptSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return QuizAttempt.objects.filter(student=self.request.user).order_by('-started_at')


# View a single quiz attempt (corrected your MyQuitAttemptView)
class MyQuizAttemptView(generics.RetrieveAPIView):
    serializer_class = QuizAttemptSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return QuizAttempt.objects.filter(student=self.request.user)


# View a single attempt’s details (same as above, for clarity)
class QuizAttemptDetailView(generics.RetrieveAPIView):
    serializer_class = QuizAttemptSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return QuizAttempt.objects.filter(student=self.request.user)


# View all attempts of a quiz (for teachers/admins)
class QuizAllAttemptsView(generics.ListAPIView):
    serializer_class = QuizAttemptSerializer
    permission_classes = [IsTeacherOrAdmin]

    def get_queryset(self):
        quiz_id = self.kwargs.get('quiz_id')
        return QuizAttempt.objects.filter(quiz_id=quiz_id).order_by('-started_at')
    
class SendResultEmailView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        attempt_id = request.data.get("attempt_id")
        attempt = get_object_or_404(QuizAttempt, id=attempt_id)

        user = request.user
        role_name = getattr(user.role, "name", "").lower() if getattr(user, "role", None) else ""

        print("USER:", user.username)
        print("IS STAFF:", user.is_staff)
        print("ROLE NAME:", role_name)

        # ✅ Allow both Admins (is_staff=True) and Teachers (role.name == "Teacher")
        if not (user.is_staff or role_name == "teacher"):
            return Response(
                {"error": f"Only teachers or admins can send emails. (Your role: {role_name or 'None'})"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Email content
        subject = f"Quiz Result for {attempt.quiz.title}"
        message = (
            f"Hello {attempt.student.username},\n\n"
            f"Your quiz '{attempt.quiz.title}' has been graded.\n"
            f"Your Score: {attempt.score}/10\n\n"
            f"Keep practicing!\n"
        )
        recipient_list = [attempt.student.email]

        send_mail(subject, message, 'no-reply@quizapp.com', recipient_list)

        return Response({"message": "Result email sent successfully!"}, status=status.HTTP_200_OK)
            



