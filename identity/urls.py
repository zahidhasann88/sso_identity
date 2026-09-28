from django.urls import path

from identity import views

urlpatterns = [
    path("auth/register/", views.register, name="auth-register"),
    path("auth/login/", views.login, name="auth-login"),
    path("auth/refresh/", views.refresh, name="auth-refresh"),
    path("auth/logout/", views.logout, name="auth-logout"),
    path("auth/introspect/", views.introspect, name="auth-introspect"),
    path("auth/password/change/", views.change_password, name="auth-password-change"),
    path("auth/me/", views.me, name="auth-me"),
    path("auth/keys/", views.public_key, name="auth-public-key"),
    path("health/", views.health, name="health"),
]
