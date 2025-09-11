import ContactModel from '../models/contactModel.js';

// Create a new contact
const createContact = async (req, res) => {
  try {
    if (!req.body) {
      return res.status(400).json({ message: 'Please provide all required fields' });
    }
    const { name, phone, email, subject, message } = req.body;
    if (!name || !phone || !email || !subject || !message) {
      return res.status(400).json({ message: 'Please provide all required fields' });
    }

    const contact = new ContactModel(req.body);
    const savedContact = await contact.save();
    return res.status(201).json(savedContact);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: err.message });
  }
};

const getAllContacts = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Run both queries concurrently
    const [total, contacts] = await Promise.all([
      ContactModel.countDocuments(),
      ContactModel.find().skip(skip).limit(limit)
    ]);

    const totalPages = Math.ceil(total / limit);

    return res.status(200).json({
      total,
      page,
      totalPages,
      limit,
      contacts,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: err.message });
  }
};


// Get contact by ID
const getContactById = async (req, res) => {
  try {
    const { id } = req.params;
    const contact = await ContactModel.findById(id);
    if (!contact) {
      return res.status(404).json({ message: 'Contact not found' });
    }
    return res.status(200).json(contact);
  } catch (err) {
    console.error(err);
    return res.status(400).json({ message: 'Invalid contact ID' });
  }
};

// Update contact by ID
const updateContact = async (req, res) => {
  try {
    const { id } = req.params;
    const updatedData = req.body;

    const updatedContact = await ContactModel.findByIdAndUpdate(id, updatedData, {
      new: true,
      runValidators: true,
    });

    if (!updatedContact) {
      return res.status(404).json({ message: 'Contact not found' });
    }
    return res.status(200).json(updatedContact);
  } catch (err) {
    console.error(err);
    return res.status(400).json({ message: err.message });
  }
};

// Delete contact by ID
const deleteContact = async (req, res) => {
  try {
    const { id } = req.params;
    const deletedContact = await ContactModel.findByIdAndDelete(id);
    if (!deletedContact) {
      return res.status(404).json({ message: 'Contact not found' });
    }
    return res.status(200).json({ message: 'Contact deleted successfully' });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ message: 'Invalid contact ID' });
  }
};

export default {
  createContact,
  getAllContacts,
  getContactById,
  updateContact,
  deleteContact,
};
