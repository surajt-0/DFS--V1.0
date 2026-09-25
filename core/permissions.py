"""Centralised, tiny permission rules for the suite's three roles:
  - admin    : sees and manages every case *within their own organization*
  - examiner : full control over cases they are assigned as investigator
  - viewer   : read-only access to every case in their organization

All access is additionally scoped to the caller's Organization (tenant) --
role does not grant cross-organization visibility.
"""
from django.core.exceptions import PermissionDenied


def _same_org(user, case) -> bool:
    org_id = getattr(user.profile, "org_id", None)
    return org_id is not None and case.organization_id == org_id


def can_view_case(user, case) -> bool:
    if not user.is_authenticated:
        return False
    if not _same_org(user, case):
        return False
    profile = user.profile
    if profile.is_admin_role or profile.is_viewer_role:
        return True
    return case.investigator_id == user.id


def can_edit_case(user, case) -> bool:
    if not user.is_authenticated:
        return False
    if not _same_org(user, case):
        return False
    from billing.access import is_org_read_only
    if is_org_read_only(case.organization):
        return False
    profile = user.profile
    if profile.is_viewer_role:
        return False
    if profile.is_admin_role:
        return True
    return case.investigator_id == user.id


def require_view(user, case):
    if not can_view_case(user, case):
        raise PermissionDenied("You do not have access to this case.")


def require_edit(user, case):
    if not can_edit_case(user, case):
        raise PermissionDenied("You do not have permission to modify this case.")


def visible_cases_qs(user, base_qs):
    profile = user.profile
    if not profile.org_id:
        return base_qs.none()
    qs = base_qs.filter(organization_id=profile.org_id)
    if profile.is_admin_role or profile.is_viewer_role:
        return qs
    return qs.filter(investigator=user)
