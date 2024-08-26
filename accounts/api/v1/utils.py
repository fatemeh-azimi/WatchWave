import jwt
from logging import getLogger
from django.contrib.auth.models import User  # Assuming you use the default User model
from django.conf import settings
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, DecodeError

logger = getLogger(__name__)  # Get logger for the current module

def log_user_action(user: User, action_type: str, extra_data: dict = None) -> None:
    """
    Logs a user action with relevant details.

    Args:
        user (User): The user object performing the action.
        action_type (str): The type of action being logged (e.g., "confirmed_account", "failed_login").
        extra_data (dict, optional): Additional data to log specific to the action. Defaults to None.
    """

    if not isinstance(user, User):
        logger.warning(f"Invalid user object passed to log_user_action: {user}")
        return

    log_message = f"User {user.username} performed action: {action_type}"

    if extra_data:
        log_message += f" - Extra data: {extra_data}"

    logger.info(log_message)


class JWTUtility:
    @staticmethod
    def decode_jwt_token(token):
        try:
            # Decode the token using the secret key
            decoded_payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            
            # Verify custom claims
            required_claims = ['username', 'role']
            for claim in required_claims:
                if claim not in decoded_payload:
                    logger.error(f"Missing claim: {claim}")
                    return None

            return decoded_payload
        except ExpiredSignatureError:
            logger.error("Token has expired")
            return None
        except DecodeError:
            logger.error("Error decoding token")
            return None
        except InvalidTokenError:
            logger.error("Invalid token")
            return None
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return None
        