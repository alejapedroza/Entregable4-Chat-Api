const router = require('express').Router()

const conversationServices = require('./conversations.services')

const passportJwt = require('../middlewares/auth.middleware')

router.route('/')
  .get(passportJwt.authenticate("jwt", { session: false }), conversationServices.getAllConversations)
  .post(passportJwt.authenticate("jwt", { session: false }), conversationServices.postConversation)

router.route('/:conversation_id')
  .get(passportJwt.authenticate('jwt', { session: false }), conversationServices.getConversationById)
  .patch(passportJwt.authenticate('jwt', { session: false }), conversationServices.patchConversation)
  .delete(passportJwt.authenticate('jwt', { session: false }), conversationServices.deleteConversation)

router.route('/:conversation_id/messages')
  .get(passportJwt.authenticate('jwt', { session: false }), conversationServices.getMessagesByConversationId)
  .post(passportJwt.authenticate('jwt', { session: false }), conversationServices.postMessage)

router.route('/:conversation_id/messages/:message_id')
  .get(passportJwt.authenticate('jwt', { session: false }), conversationServices.getMessageById)
  .delete(passportJwt.authenticate('jwt', { session: false }), conversationServices.deleteMessage)

module.exports = router