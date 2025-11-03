from django.urls import path
from .views import (
    UserCRUDView,
    RoleListView,
    PermissionListView,
    CustomTokenObtainPairView,
    StudentSignupView,
    VerifyStudentView,
    StudentListView,
    TeacherListAPIView,
    StudentsAwaitingVerificationAPIView,
    AllStudentsListView
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # JWT
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Users: list/create and detail (GET, PUT, DELETE)
    path('api/users/', UserCRUDView.as_view(), name='users-list-create'),            # GET all / POST create
    path('api/users/<int:user_id>/', UserCRUDView.as_view(), name='users-detail'),   # GET / PUT / DELETE by ID

    # Assign role to a user (POST) - expects {"role": <role_id>}
    path('api/users/<int:user_id>/assign-role/',            # POST only
         UserCRUDView.as_view(), name='users-assign-role'), # route handled by a separate view in backend ideally
    path('admin/teachers/', TeacherListAPIView.as_view(), name='teacher-list'),
    path('teacher/students-awaiting-verification/', StudentsAwaitingVerificationAPIView.as_view(), name='students-awaiting-verification'),
    path('students/all/', AllStudentsListView.as_view(), name='all-students'),


    # Roles & Permissions listing
    path('api/roles/', RoleListView.as_view(), name='roles-list'),
    path('api/permissions/', PermissionListView.as_view(), name='permissions-list'),

    # Assign permission to role (POST) - expects {"permission": <permission_id>}
    path('api/roles/<int:role_id>/assign-permission/',
         RoleListView.as_view(), name='roles-assign-permission'),  # implement a small view to handle this

    path('api/students/signup/', StudentSignupView.as_view(), name='student-signup'),
    path('api/students/<int:student_id>/verify/', VerifyStudentView.as_view(), name='verify-student'),
    path("api/students/", StudentListView.as_view(), name="students-list")
]
