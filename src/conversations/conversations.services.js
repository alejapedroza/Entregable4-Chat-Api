const conversationControllers = require('./conversations.controllers')

const getAllConversations =(req, res) => {
  conversationControllers.findAllConversations()
    .then((data) => {
      res.status(200).json(data)
    })
    .catch((err) => {
      res.status(400).json({message: 'Bad request', err})
    })
}

const getConversationById = (req, res) => {
  const id = req.params.conversation_id
  conversationControllers.findConversationById(id)
    .then((data) => {
      if(data) {
        res.status(200).json(data)
    } else {
        res.status(404).json({message: 'Conversation not found'})
    }
    })
    .catch((err) => {
      res.status(400).json({err: err.message})
    })
}

const getAllConversationsByUser = (req, res) => {
  const id = req.user.id
  conversationControllers.findAllConversationsByUser(id)
    .then((data) => {
      res.status(200).json(data)
    })
    .catch((err) => {
      res.status(400).json({err: err.message})
    })
}

const postConversation = (req, res) => {
  const conversationObj = req.body
  const ownerId = req.user.id 
  conversationControllers.createConversation({...conversationObj, ownerId})
      .then(data => {
          if(!data) {
              return res.status(404).json({message: 'Guest ID not exists'})
          }
          res.status(201).json(data)
      })
      .catch(err => {
          res.status(400).json({err: err.message})
      })
}

const patchConversation = (req, res) => {
  const id = req.params.conversation_id
  const { name, profileImage,isGroup } = req.body
  conversationControllers.updateConversation(id, {name, profileImage,isGroup})
    .then((data) => {
      if(data) {
        res.status(200).json(data)
      } else {
          res.status(404).json({message: "Conversation not found"})
      }
    })
    .catch((err) => {
      res.status(400).json({err: err.message})
    })
}

const deleteConversation = (req, res) => {
  const id = req.params.conversation_id
  conversationControllers.removeConversation(id)
    .then((data) => {
      if(!data) {
        return res.status(404).json({message: 'Invalid ID'})
      }
      res.status(204).json()
    })
    .catch((err) => {
      res.status(400).json({message: 'Bad request', err})
    })
}

const getMessagesByConversationId = (req, res) => {
  const id = req.params.conversation_id
  conversationControllers.findAllMessagesByConversationId(id)
    .then((data) => {
      if(data) {
        res.status(200).json(data)
      } else {
        res.status(404).json({message: 'Invalid ID'})
      }
    })
    .catch((err) => {
      res.status(400).json({err: err.message})
    })
}

const postMessage = (req, res) => {
  const id = req.params.conversation_id
  const { content, participantId} = req.body
  conversationControllers.createMessage(id, {content, participantId})
    .then((data) => {
      res.status(201).json(data)
    })
    .catch((err) => {
      res.status(400).json({err})
    })
}

const getMessageById = (req, res) => {
  const id = req.params.message_id
  conversationControllers.findMessageById(id)
    .then((data) => {
      if(data) {
        res.status(200).json(data)
      } else {
        res.status(404).json({message: 'Invalid ID'})
      }
    })
    .catch((err) => {
      res.status(400).json({err: err.message})
    })
}

const deleteMessage = (req, res) => {
  const id = req.params.message_id
  conversationControllers.removeMessageById(id)
    .then((data) => {
      if(!data) {
        return res.status(404).json({message: 'Invalid ID'})
      }
      res.status(204).json()
    })
    .catch((err) => {
      res.status(400).json({err: err.message})
    })
}

module.exports = { 
  getAllConversations,
  getConversationById,
  postConversation,
  patchConversation,
  deleteConversation,
  getAllConversationsByUser,
  getMessagesByConversationId,
  postMessage,
  getMessageById,
  deleteMessage
}