









import { verifyPassword, hashPassword } from '../core/security/password.js';
import type { IStorageAdapter } from '../storage/interface.js';




export interface HandleValidatorConfig {
  
  storage: IStorageAdapter;
  
  logger?: (level: string, message: string, data?: Record<string, unknown>) => void;
  
  timingDelayMs?: number;
}

export interface HandleValidationResult {
  isValid: boolean;
  userId?: string;
}









export async function validateHandle(
  handle: string,
  password: string,
  config: HandleValidatorConfig
): Promise<HandleValidationResult> {
  const { storage, logger = () => {}, timingDelayMs = 100 } = config;

  const user = await storage.getUserByHandle(handle);

  if (!user) {
    logger('debug', 'No user found for handle', { handle });
    
    await new Promise(resolve => setTimeout(resolve, timingDelayMs));
    return { isValid: false };
  }

  if (!user.isActive) {
    logger('debug', 'User is inactive', { handle });
    await new Promise(resolve => setTimeout(resolve, timingDelayMs));
    return { isValid: false };
  }

  try {
    const isValid = await verifyPassword(password, user.passwordHash);

    if (isValid) {
      return {
        isValid: true,
        userId: user.id,
      };
    }
  } catch (error) {
    logger('error', 'Password validation error', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }

  return { isValid: false };
}









export async function addHandle(
  handle: string,
  password: string,
  config: HandleValidatorConfig
): Promise<boolean> {
  const { storage, logger = () => {} } = config;

  try {
    
    const existing = await storage.getUserByHandle(handle);
    if (existing) {
      logger('warn', 'Handle already exists', { handle });
      return false;
    }

    const passwordHash = await hashPassword(password);

    await storage.createUser({
      handle,
      email: '',
      passwordHash,
      role: 'admin',
      isActive: true,
      needsOnboarding: true,
      onboardingStep: 0,
      totpEnabled: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    logger('info', 'Handle added successfully', { handle });
    return true;
  } catch (error) {
    logger('error', 'Error adding handle', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    return false;
  }
}








export async function removeHandle(
  handle: string,
  config: HandleValidatorConfig
): Promise<boolean> {
  const { storage, logger = () => {} } = config;

  try {
    const user = await storage.getUserByHandle(handle);
    if (!user) {
      logger('warn', 'Handle not found for removal', { handle });
      return false;
    }

    const deleted = await storage.deleteUser(user.id);
    if (deleted) {
      logger('info', 'Handle removed successfully', { handle });
    }
    return deleted;
  } catch (error) {
    logger('error', 'Error removing handle', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    return false;
  }
}







export async function listHandles(
  config: HandleValidatorConfig
): Promise<string[] | null> {
  const { storage, logger = () => {} } = config;

  try {
    const users = await storage.getAllUsers();
    return users
      .filter(u => u.isActive)
      .map(u => u.handle);
  } catch (error) {
    logger('error', 'Error listing handles', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    return null;
  }
}
