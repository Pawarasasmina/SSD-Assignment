import React, { useState, useEffect } from 'react';
import axios from 'axios';
import FeedbackCard from '../components/FeedbackCard';
import { jsPDF } from 'jspdf'; // Import jsPDF
const FeedbackList = () => {
    const [feedbacks, setFeedbacks] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');
    const [filterType, setFilterType] = useState('All');

    const userId = localStorage.getItem("userId"); 

    useEffect(() => {
        const fetchFeedbacks = async () => {
            try {
                const res = await axios.get(`http://localhost:3000/api/feedback/${userId}`);
                setFeedbacks(res.data);
            } catch (error) {
                console.error("Error fetching feedbacks:", error);
            }
        };

        fetchFeedbacks();
    }, []);

    const handleUpdate = async (updatedReview) => {
        const userId = localStorage.getItem("userId"); 
        try {
            // Fetch the latest feedbacks after updating
            const response = await axios.get(`http://localhost:3000/api/feedback/${userId}`);
            const latestFeedbacks = response.data;
    
            // Update the state with the latest feedbacks
            setFeedbacks(latestFeedbacks);
        } catch (error) {
            console.error("Error fetching latest feedbacks:", error);
        }
    };
    

    const handleDelete = (id) => {
        setFeedbacks((prevFeedbacks) => prevFeedbacks.filter((feedback) => feedback._id !== id));
    };

    const filteredFeedbacks = feedbacks.filter((feedback) => {
        const matchesSearch = 
            feedback.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
            feedback.content.toLowerCase().includes(searchTerm.toLowerCase());
        
        const matchesFilter = filterType === 'All' || feedback.feedbackFor === filterType;

        return matchesSearch && matchesFilter;
    });

    const generatePDFReport = () => {
        const doc = new jsPDF();
        doc.setFontSize(18);
        doc.text('Filtered Feedback Report', 10, 10);

        let y = 20;

        filteredFeedbacks.forEach((feedback, index) => {
            doc.setFontSize(12);
            doc.text(`${index + 1}. Title: ${feedback.title}`, 10, y);
            doc.text(`Content: ${feedback.content}`, 10, y + 10);
            doc.text(`Rating: ${feedback.rating}`, 10, y + 20);
            doc.text(`Category: ${feedback.feedbackFor}`, 10, y + 30);
            doc.text(`Type: ${feedback.feedbackType}`, 10, y + 40);
            doc.text(`Created At: ${new Date(feedback.createdAt).toLocaleDateString()}`, 10, y + 50);

            y += 60;

            // If page is full, add a new page
            if (y > 270) {
                doc.addPage();
                y = 20;
            }
        });

        // Save the PDF
        doc.save('Feedback_Report.pdf');
    };

    return (
        <div className="feedback-list-container p-6 bg-gray-600 min-h-screen w-[99vw]">
            <div className="controls-container mb-4 flex justify-between items-center">
                <div className="search-container">
                    <input
                        type="text"
                        placeholder="Search feedback..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="search-input border border-gray-300 rounded-lg p-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                </div>
                <div className="filter-container">
                    <select 
                        value={filterType} 
                        onChange={(e) => setFilterType(e.target.value)} 
                        className="filter-select border border-gray-300 rounded-lg p-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                        <option value="All">All Feedback</option>
                        <option value="Item">Item Feedback</option>
                        <option value="Shop">Shop Feedback</option>
                    </select>
                </div>
                {/* Generate PDF button */}
                <button 
                    className="generate-pdf-button bg-blue-600 text-white rounded-lg px-4 py-2 hover:bg-blue-700 transition duration-300"
                    onClick={generatePDFReport}
                >
                    Generate Report
                </button>
            </div>

            <div className="feedback-list grid grid-cols-1 bg-gray-600  md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredFeedbacks.map((review) => (
                    <FeedbackCard
                        key={review._id}
                        review={review}
                        onDelete={handleDelete}
                        onUpdate={handleUpdate}
                    />
                ))}
            </div>
        </div>
    );
};

export default FeedbackList;
