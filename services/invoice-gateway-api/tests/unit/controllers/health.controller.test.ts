/**
 * Health Controller Tests
 */

import { Request, Response } from 'express';
import { Container } from 'inversify';
import { HealthController } from '../../../src/controllers/health.controller';

describe('HealthController', () => {
  let controller: HealthController;
  let container: Container;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;

  beforeEach(() => {
    container = new Container();
    controller = new HealthController(container);

    mockRequest = {};
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
  });

  describe('healthCheck', () => {
    it('should return UP status when all dependencies are healthy', async () => {
      await controller.healthCheck(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'UP',
          dependencies: expect.any(Object),
          version: '1.0.0',
          service: 'invoice-gateway-api',
        })
      );
    });

    it('should include timestamp in response', async () => {
      await controller.healthCheck(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/),
        })
      );
    });
  });

  describe('readinessCheck', () => {
    it('should return ready:true when service is ready', async () => {
      await controller.readinessCheck(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          ready: true,
        })
      );
    });
  });

  describe('livenessCheck', () => {
    it('should return alive:true', () => {
      controller.livenessCheck(mockRequest as Request, mockResponse as Response);

      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          alive: true,
        })
      );
    });
  });
});
