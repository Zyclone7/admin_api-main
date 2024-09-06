const express = require('express')
const router = express.Router()
const { registerUser, loginUser, getMe, readAllUsersWithRoles, deleteUser, getUserById, updateUser} = require('../controllers/userController')

const { protect, admin } = require('../middleware/authMiddleware')


router.post('/', registerUser)
router.post('/login', loginUser)
router.get('/all', protect, admin, readAllUsersWithRoles);
router.get('/:id', protect, admin, getUserById);
router.delete('/:id', protect, admin, deleteUser);
router.put('/:id', protect, updateUser);





module.exports = router