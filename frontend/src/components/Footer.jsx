// src/components/Footer.jsx
import React from "react";
import { FaFacebook, FaTwitter, FaInstagram, FaLinkedin } from "react-icons/fa";

const Footer = () => {
  return (
    <footer className="bg-[#212529] text-white">
      <div className="container mx-auto py-8 px-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
        <div className="footer-section">
          <h3 className="text-xl font-bold text-[#ff9800] mb-4">About Us</h3>
          <p className="text-sm leading-relaxed">
            Shopping Eye is your one-stop shop for the best deals and exclusive
            offers. Explore our wide range of products and enjoy shopping like
            never before.
          </p>
        </div>
        <div className="footer-section">
          <h3 className="text-xl font-bold text-[#ff9800] mb-4">Quick Links</h3>
          <ul className="space-y-2">
            <li>
              <a href="#home" className="hover:text-[#ff9800] transition">
                Home
              </a>
            </li>
            <li>
              <a href="#categories" className="hover:text-[#ff9800] transition">
                Categories
              </a>
            </li>
            <li>
              <a href="#offers" className="hover:text-[#ff9800] transition">
                Offers
              </a>
            </li>
            <li>
              <a href="#shops" className="hover:text-[#ff9800] transition">
                Shops
              </a>
            </li>
            <li>
              <a href="#contact" className="hover:text-[#ff9800] transition">
                Contact
              </a>
            </li>
          </ul>
        </div>
        <div className="footer-section">
          <h3 className="text-xl font-bold text-[#ff9800] mb-4">Contact Us</h3>
          <p className="text-sm leading-relaxed">Email: support@shoppingeye.com</p>
          <p className="text-sm leading-relaxed">Phone: +123 456 7890</p>
        </div>
        <div className="footer-section">
          <h3 className="text-xl font-bold text-[#ff9800] mb-4">Follow Us</h3>
          <div className="flex space-x-4 text-2xl">
            <a
              href="https://facebook.com"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-[#ff9800] transition"
            >
              <FaFacebook />
            </a>
            <a
              href="https://twitter.com"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-[#ff9800] transition"
            >
              <FaTwitter />
            </a>
            <a
              href="https://instagram.com"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-[#ff9800] transition"
            >
              <FaInstagram />
            </a>
            <a
              href="https://linkedin.com"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-[#ff9800] transition"
            >
              <FaLinkedin />
            </a>
          </div>
        </div>
      </div>
      <div className="bg-black py-4">
        <div className="container mx-auto text-center">
          <p className="text-sm text-[#ff9800]">&copy; 2024 Shopping Eye. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
