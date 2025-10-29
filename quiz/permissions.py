from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsTeacherOrAdmin(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return (
            user.is_authenticated and
            user.role and 
            user.role.name in ["Admin", "Teacher"]
        )

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return (
            user.is_authenticated and
            user.role and 
            user.role.name == "Admin"
        )
    
class IsTeacherOrAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.role and request.user.role.name.lower() in ['admin', 'teacher']
        )
    
class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.role and request.user.role.name.lower()=='admin'
        )
    
class IsVerifiedStudent(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.role and request.user.role.name.lower() == 'student' and request.user.is_verified
        )
    
