import express from "express";
import {
  createUser,
  loginUser,
  logOutCurrentUser,
  getAllUsers,
  getCurrentUserProfile,
  updateCurrentUser,
  deleteUserById,
  getUserByID,
  updateUserById,
} from "../controllers/userController.js";
import {
  authenticate,
  authorizeAsAdmin,
} from "../middlewares/authMiddleware.js";

const router = express.Router();

router
  .route("/")
  .post(createUser)
  .get(authenticate, authorizeAsAdmin, getAllUsers);
router.post("/auth", loginUser);
router.post("/logout", logOutCurrentUser);
router
  .route("/profile")
  .get(authenticate, getCurrentUserProfile)
  .put(authenticate, updateCurrentUser);

// Admin Routes
router
  .route("/:id")
  .delete(authenticate, authorizeAsAdmin, deleteUserById)
  .get(authenticate, authorizeAsAdmin, getUserByID)
  .put(authenticate, authorizeAsAdmin, updateUserById);

export default router;
