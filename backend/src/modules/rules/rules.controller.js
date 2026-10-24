// src/modules/rules/rules.controller.js
// Controllers for Detection Rules management and configuration.

import prisma from '../../config/prisma.js';
import { validateRuleUpdatePayload, validateRuleConfig } from './rules.validation.js';

/**
 * GET /api/rules
 * Returns all detection rules.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 */
export async function getRules(_req, res, next) {
  try {
    const rules = await prisma.detectionRule.findMany({
      orderBy: { name: 'asc' },
      select: {
        id: true,
        name: true,
        type: true,
        description: true,
        severity: true,
        enabled: true,
        config: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return res.status(200).json({
      success: true,
      data: rules,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * PUT /api/rules/:id
 * Updates a detection rule's enabled status, description, severity, or configuration.
 * Allowed roles: ADMIN only.
 */
export async function updateRule(req, res, next) {
  try {
    const { id } = req.params;

    if (!id || typeof id !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Invalid or missing rule ID.',
      });
    }

    // 1. Check if the rule exists
    const rule = await prisma.detectionRule.findUnique({
      where: { id },
    });

    if (!rule) {
      return res.status(404).json({
        success: false,
        error: `Detection rule not found with ID "${id}".`,
      });
    }

    // 2. Validate top-level request body
    const payloadError = validateRuleUpdatePayload(req.body);
    if (payloadError) {
      return res.status(400).json({
        success: false,
        error: payloadError,
      });
    }

    // 3. Process and validate config updates (if provided)
    const updateData = {};
    const previousValues = {};
    const updatedValues = {};

    if ('enabled' in req.body) {
      updateData.enabled = req.body.enabled;
      previousValues.enabled = rule.enabled;
      updatedValues.enabled = req.body.enabled;
    }

    if ('description' in req.body) {
      updateData.description = req.body.description;
      previousValues.description = rule.description;
      updatedValues.description = req.body.description;
    }

    if ('severity' in req.body) {
      updateData.severity = req.body.severity;
      previousValues.severity = rule.severity;
      updatedValues.severity = req.body.severity;
    }

    if ('config' in req.body) {
      // Merge partial config into existing rule configuration
      const existingConfig = rule.config && typeof rule.config === 'object' ? rule.config : {};
      const mergedConfig = { ...existingConfig, ...req.body.config };

      const configError = validateRuleConfig(rule.type, req.body.config, mergedConfig);
      if (configError) {
        return res.status(400).json({
          success: false,
          error: configError,
        });
      }

      updateData.config = mergedConfig;
      previousValues.config = rule.config;
      updatedValues.config = mergedConfig;
    }

    // 4. Atomic update of rule and audit log in a single transaction
    const updatedRule = await prisma.$transaction(async (tx) => {
      const result = await tx.detectionRule.update({
        where: { id: rule.id },
        data: updateData,
        select: {
          id: true,
          name: true,
          type: true,
          description: true,
          severity: true,
          enabled: true,
          config: true,
          createdAt: true,
          updatedAt: true,
        },
      });

      await tx.auditLog.create({
        data: {
          userId: req.user.id,
          action: 'RULE_UPDATE',
          targetType: 'DetectionRule',
          targetId: rule.id,
          ipAddress: req.ip || req.socket?.remoteAddress || null,
          details: {
            ruleName: rule.name,
            ruleType: rule.type,
            changedFields: Object.keys(updateData),
            previous: previousValues,
            updated: updatedValues,
          },
        },
      });

      return result;
    });

    return res.status(200).json({
      success: true,
      message: `Detection rule "${updatedRule.name}" updated successfully.`,
      data: updatedRule,
    });
  } catch (err) {
    next(err);
  }
}
